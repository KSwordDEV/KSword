#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QVector>
#include <QtGlobal>

// Capture this context before dispatching a worker. Access never silently
// changes its source or registry view after a permission or protocol failure.
struct RegistryAccessContext
{
    int viewBits = 0;
    bool useR0 = false;
};

struct RegistryValueState
{
    QString name;
    quint32 type = 0;
    QByteArray data;
    bool exists = false;
    bool complete = true;
    quint32 requiredBytes = 0;
};

struct RegistryKeyListing
{
    QVector<RegistryValueState> values;
    QStringList subKeys;
    bool complete = true;
    QString warning;
};

class RegistryWorkbenchAccess final
{
public:
    static bool read(const QString& path, const QString& name,
        const RegistryAccessContext& context, RegistryValueState* state, QString* error);
    static bool enumerate(const QString& path, const RegistryAccessContext& context,
        RegistryKeyListing* listing, QString* error, bool includeSubKeys = true);
    static bool write(const QString& path, const RegistryValueState& state,
        const RegistryAccessContext& context, QString* error);
    static bool removeValue(const QString& path, const QString& name,
        const RegistryAccessContext& context, QString* error);
    static bool createKey(const QString& path, const RegistryAccessContext& context, QString* error);
    // 查询键存在性与同父键重命名都显式传递冻结视图/通道，不根据 UI 再决策。
    static bool keyExists(const QString& path, const RegistryAccessContext& context,
        bool* exists, QString* error);
    static bool renameKey(const QString& path, const QString& newName,
        const RegistryAccessContext& context, QString* newPath, QString* error);
    // HKCR is a merged Win32 view and intentionally has no R0 approximation.
    static QString kernelPath(const QString& path);
};
