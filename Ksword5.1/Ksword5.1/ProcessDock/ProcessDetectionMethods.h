#pragma once

#include "../ArkDriverClient/ArkDriverTypes.h"

#include <QDateTime>
#include <QString>
#include <QVector>
#include <cstdint>
#include <functional>
#include <optional>

namespace ksword::detection
{
    using MethodMask = std::uint64_t;
    inline constexpr MethodMask ProcessBaseline = 1ULL << 0;
    inline constexpr MethodMask ThreadOwners = 1ULL << 1;
    inline constexpr MethodMask DesktopWindows = 1ULL << 2;
    inline constexpr MethodMask NetworkEndpoints = 1ULL << 3;
    inline constexpr MethodMask ProcessCrossView = 1ULL << 4;
    inline constexpr MethodMask ThreadCrossView = 1ULL << 5;
    inline constexpr MethodMask ProcessHandles = 1ULL << 6;
    inline constexpr MethodMask CsrssHandles = 1ULL << 7;
    inline constexpr MethodMask CallbackHistory = 1ULL << 8;
    inline constexpr MethodMask ActiveProcesses = 1ULL << 9;
    inline constexpr MethodMask CidProcesses = 1ULL << 10;
    inline constexpr MethodMask LinkedThreads = 1ULL << 11;
    inline constexpr MethodMask CidThreads = 1ULL << 12;
    inline constexpr MethodMask ProcessKernelMethods = ProcessCrossView | ActiveProcesses | CidProcesses;
    inline constexpr MethodMask ThreadKernelMethods = ThreadCrossView | LinkedThreads | CidThreads;

    enum class Cost { Fast, Moderate, Slow };
    enum class Status { Complete, Partial, Unavailable, Failed, Cancelled };
    struct Method
    {
        MethodMask bit;
        QString name;
        Cost cost;
    };
    struct ScanInputs
    {
        QString memoryImage;
        QString volatilityProgram;
        QString memProcFsRoot;
        QString eventTraceFile;
        QString flatPhysicalImage;
    };
    struct MethodReport
    {
        MethodMask method = 0;
        Status status = Status::Complete;
        qint64 elapsedMs = 0;
        quint64 count = 0;
        QString detail;
    };
    struct Evidence
    {
        quint32 pid = 0;
        quint64 creationTime100ns = 0; // Windows FILETIME from the observed object, or unknown.
        quint64 objectAddress = 0;
        MethodMask methods = 0;
        QString image;
        QString detail;
        bool absentFromBaseline = false;
        bool historical = false;
        QString scope; // Non-local evidence is never compared with the live host baseline.
        QString category;
        bool lifetimeUnknown = false;
    };
    struct ScanResult
    {
        QDateTime startedUtc;
        MethodMask selected = 0;
        bool cancelled = false;
        QVector<MethodReport> reports;
        QVector<Evidence> evidence;
        std::optional<ark::ProcessCrossViewResult> processCrossView;
        std::optional<ark::ThreadCrossViewResult> threadCrossView;
    };

    QVector<Method> Methods();
    MethodMask Defaults(bool deep);
    quint32 ComparableAnomalies(const ScanResult& result, const ark::ProcessCrossViewEntry& entry);
    quint32 ComparableAnomalies(const ScanResult& result, const ark::ThreadCrossViewEntry& entry);
    ScanResult Run(MethodMask selected, const std::function<bool()>& cancelled = {},
        const ScanInputs& inputs = {});
}
