#pragma once
#include "ProcessDetectionMethods.h"

namespace ksword::detection
{
    // Empty when the selection needs no special layout or existing shared fields already suffice.
    QString PrepareDetectionLayout(const ResearchSet& selected, const QString& profileDirectory = {});
    bool VerifyPreparedDetectionLayout(const ResearchSet& selected);
}
