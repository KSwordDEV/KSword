#pragma once
#include "ArkDriverClient.h"
#include "ArkLocalDynDataProfile.h"
#include <QString>

namespace ksword::ark
{
    struct ProcessLifetimeProfileResult
    {
        bool ready = false;
        bool applied = false;
        QString detail;
    };

    // Background-only preparation, independent of KernelDock widget creation.
    // A failure supplies diagnostics and never authorizes dropping candidates.
    ProcessLifetimeProfileResult prepareProcessLifetimeProfile(const DriverClient& client,
        const DynDataProfileText& texts = {});
}
