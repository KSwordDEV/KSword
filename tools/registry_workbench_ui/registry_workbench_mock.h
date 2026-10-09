#pragma once
#include "RegistryDock/RegistryWorkbenchAccess.h"
#include <atomic>
#include <QString>

namespace registry_ui
{
    extern std::atomic_bool driverEnabled;
    extern std::atomic_int reads;
    extern std::atomic_int writes;
    extern std::atomic_int blockedReads;
    extern std::atomic_int win32KeyRenames;
    extern std::atomic_int r0KeyRenames;
    void seed();
    void blockReads(bool block);
    RegistryValueState get(const QString& path, const QString& name, int view = 0);
    void set(const QString& path, const QString& name, quint32 type, const QByteArray& data, int view = 0);
}
