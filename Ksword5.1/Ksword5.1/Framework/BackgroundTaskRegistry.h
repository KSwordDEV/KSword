#pragma once

#include <QObject>
#include <QPointer>
#include <QHash>
#include <QDateTime>
#include <QString>
#include <QVector>
#include <QSet>
#include <functional>
#include <chrono>
#include "TaskCpuMeasurement.h"

class QTimer;

namespace ks::ui
{
    // UI-thread registry for long-lived polling. Existing timers retain their owner,
    // async dispatch and cancellation semantics; registration never starts a timer.
    class BackgroundTaskRegistry final : public QObject
    {
    public:
        struct Policy
        {
            bool canPause = true;
            bool canChangeInterval = true;
            int minimumIntervalMs = 100;
            int maximumIntervalMs = 60000;
            QString restriction;
            bool allowMultipleInstances = false; // Temporary instances do not persist interval overrides.
            std::function<bool()> eligible;
            std::function<bool()> inFlight;
        };
        struct Snapshot
        {
            QString id, title, group, restriction;
            int intervalMs = 0, defaultIntervalMs = 0, minimumIntervalMs = 0, maximumIntervalMs = 0;
            bool active = false, paused = false, inFlight = false, canPause = false, canChangeInterval = false;
            quint64 dispatches = 0;
            QDateTime lastDispatch;
            TaskCpuStats cpu;
            bool cpuSupported = false;
            unsigned cpuInFlight = 0;
        };
        struct External
        {
            std::function<bool()> running;
            std::function<bool()> paused;
            std::function<bool(bool)> pause;
        };

        static BackgroundTaskRegistry& instance();
        explicit BackgroundTaskRegistry(QObject* parent = nullptr, QString settingsPath = {});
        ~BackgroundTaskRegistry() override;
        bool addTimer(const QString& id, const QString& title, const QString& group,
            QTimer* timer, Policy policy);
        bool addExternal(const QString& id, const QString& title, const QString& group,
            QObject* owner, External binding, const QString& restriction);
        QVector<Snapshot> snapshot() const;
        bool setPaused(const QString& id, bool paused, QString* error = nullptr);
        bool setInterval(const QString& id, int milliseconds, QString* error = nullptr);
        bool restoreDefault(const QString& id, QString* error = nullptr);
        bool isPaused(const QString& id) const;
        static QString defaultSettingsPath();
        struct CpuAnalysis
        {
            bool started = false, active = false, processAvailable = false;
            double seconds = 0, processCpuMs = 0, processCpuPercent = 0;
        };
        void startCpuAnalysis(); // A new session resets counters, never business tasks.
        void stopCpuAnalysis();
        CpuAnalysis cpuAnalysis() const;
        TaskCpuToken cpuToken(const QString& id) const;
        static TaskCpuToken cpuTokenForEvent(QObject* receiver, QEvent* event);
        static bool cpuAnalysisEnabled() { return s_cpuEnabled.load(std::memory_order_relaxed); }

    protected:
        bool eventFilter(QObject* object, QEvent* event) override;

    private:
        struct Entry
        {
            Snapshot value;
            QPointer<QTimer> timer;
            QPointer<QObject> owner;
            External external;
            Policy policy;
            bool resumeActive = false;
            int overrideIntervalMs = 0;
            quint64 generation = 0;
            TaskCpuToken cpu;
        };
        bool fail(QString* error, const QString& message) const;
        QHash<QString, Entry> m_entries;
        QHash<QObject*, QString> m_timerIds;
        QSet<QObject*> m_rejectedTimers;
        QString m_settingsPath;
        quint64 m_instanceSerial = 0;
        std::shared_ptr<TaskCpuSession> m_cpuSession;
        std::chrono::steady_clock::time_point m_cpuStarted;
        TaskCpuReading m_processBaseline;
        unsigned long m_cpuCount = 0;
        CpuAnalysis m_frozenCpu;
        inline static std::atomic_bool s_cpuEnabled{false};
    };
}
