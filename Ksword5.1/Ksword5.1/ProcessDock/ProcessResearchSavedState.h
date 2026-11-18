#pragma once
#include "ProcessDetectionForensics.h"
#include <QByteArray>

namespace ksword::detection
{
    struct VmrsProcessFiles
    {
        QString sourceFile, library;
        QByteArray systemInfo, processes;
    };
    bool ReadVmrsProcessFiles(HMODULE vmm, const QString& file, QByteArray& systemInfo, QByteArray& processes,
        MethodReport& report, const CancelCheck& stop);
}
